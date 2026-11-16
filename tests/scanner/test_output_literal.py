"""guard's human report shows findings and scanner text exactly as reported (#957).

The report passed rule ids, descriptions, previews, skip reasons, scanner
errors and configured paths to Rich as markup. A closing tag such as ``[/x]``
raised ``MarkupError`` (a traceback instead of the report, exit 1), and a tag
Rich knows, such as ``[bold]``, vanished, so the report named a file that does
not exist. Square brackets are ordinary in paths (``cfg[prod]/``, Next.js
``[id]/`` routes), and the other fields come from external scanners.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from rich.console import Console
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.guard import _print_scan_header
from envdrift.scanner.base import (
    EXIT_CRITICAL_FINDINGS,
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScanResult,
)
from envdrift.scanner.engine import ScanEngine
from envdrift.scanner.output import format_rich

runner = CliRunner()

_AWS_KEY_LINE = "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLQ\n"

# A Windows path that rich.markup.escape() cannot round-trip: it drops the
# backslash in front of a bracket that is not a tag.
_WINDOWS_PATH = "C:\\[2024]\\x"


def _repo(tmp_path: Path, folder: str) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    target = tmp_path / folder
    target.mkdir(parents=True)
    (target / "a.env").write_text(_AWS_KEY_LINE, encoding="utf-8")
    return tmp_path


def _guard(*args: str):
    return runner.invoke(app, ["guard", *args], env={"COLUMNS": "250"})


@pytest.mark.parametrize("ci", [False, True], ids=["human", "ci"])
def test_closing_tag_in_a_path_is_reported_instead_of_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ci: bool
) -> None:
    monkeypatch.chdir(_repo(tmp_path, "cfg[/x]"))

    result = _guard(".", "--native-only", *(["--ci"] if ci else []))

    assert result.exit_code == EXIT_CRITICAL_FINDINGS, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    expected = "Run 'envdrift encrypt " + str(Path("cfg[/x]/a.env")) + "' before committing."
    assert expected in " ".join(result.output.split())


def test_known_tag_in_a_path_names_the_real_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``cfg[bold]/a.env`` used to be suggested as ``cfg/a.env``, a file that does not exist."""
    monkeypatch.chdir(_repo(tmp_path, "cfg[bold]"))

    result = _guard(".", "--native-only", "--ci")

    assert result.exit_code == EXIT_CRITICAL_FINDINGS, result.output
    real = str(Path("cfg[bold]/a.env"))
    assert f"Run 'envdrift encrypt {real}' before committing." in result.output
    assert "envdrift encrypt " + str(Path("cfg/a.env")) not in result.output


def _finding() -> ScanFinding:
    return ScanFinding(
        file_path=Path("cfg[/x]/a.env"),
        rule_id="rule[/x]",
        rule_description="Rule",
        description=f"found in cfg[bold]/a.env and {_WINDOWS_PATH}",
        severity=FindingSeverity.HIGH,
        scanner="gitleaks",
        secret_preview="ab[/x]",
    )


def _aggregate(*results: ScanResult) -> AggregatedScanResult:
    findings = [f for r in results for f in r.findings]
    return AggregatedScanResult(
        results=list(results),
        total_findings=len(findings),
        unique_findings=findings,
        scanners_used=[r.scanner_name for r in results],
        total_duration_ms=1,
    )


@pytest.mark.parametrize(
    "console",
    [
        pytest.param(
            Console(record=True, force_terminal=False, no_color=True, width=250, _environ={}),
            id="wide-log",
        ),
        pytest.param(
            Console(record=True, force_terminal=True, width=250, _environ={}),
            id="wide-terminal",
        ),
        pytest.param(
            Console(record=True, force_terminal=True, width=90, _environ={}),
            id="narrow-terminal",
        ),
        pytest.param(
            Console(record=True, force_terminal=False, no_color=True, width=80, _environ={}),
            id="narrow-log",
        ),
    ],
)
def test_every_findings_layout_shows_the_finding_as_reported(console: Console) -> None:
    format_rich(_aggregate(ScanResult(scanner_name="gitleaks", findings=[_finding()])), console)

    out = " ".join(console.export_text().split())
    assert f"found in cfg[bold]/a.env and {_WINDOWS_PATH}" in out
    if console.width >= 100 or not console.is_terminal:
        assert "rule[/x]" in out
        assert "ab[/x]" in out


def test_scanner_error_is_shown_as_reported() -> None:
    """``format_rich`` with ``error="cannot read cfg[/x]/a.env"`` raised MarkupError."""
    error = f"cannot read cfg[/x]/a.env or {_WINDOWS_PATH}"
    console = Console(record=True, force_terminal=True, color_system="standard", width=200)

    format_rich(_aggregate(ScanResult(scanner_name="gitleaks", error=error)), console)

    assert f"gitleaks: {error}" in console.export_text(clear=False)
    # The scanner name keeps its red styling.
    assert "\x1b[31mgitleaks\x1b[0m" in console.export_text(styles=True)


def test_skip_reason_and_warning_are_shown_as_reported() -> None:
    skip = "gitleaks [/x] is not installed"
    warning = f"detect-secrets at {_WINDOWS_PATH} is not the pinned version"
    console = Console(record=True, force_terminal=True, color_system="standard", width=200)
    result = _aggregate(
        ScanResult(scanner_name="gitleaks", skip_reason=skip),
        ScanResult(scanner_name="detect-secrets", warnings=[warning]),
    )

    format_rich(result, console)

    out = console.export_text(clear=False)
    assert f"gitleaks: {skip}" in out
    assert f"detect-secrets: {warning}" in out
    styled = console.export_text(styles=True)
    assert "\x1b[33mgitleaks\x1b[0m" in styled
    assert "\x1b[33mdetect-secrets\x1b[0m" in styled


def test_combined_file_warning_names_the_configured_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The .gitignore warning for a combined file raised MarkupError on a bracketed path."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "production"\n'
        'clear_file = "cfg[/x]/.env.production.clear"\n'
        'secret_file = "cfg[/x]/.env.production.secret"\n'
        'combined_file = "cfg[/x]/.env.production"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.txt").write_text("nothing to see\n", encoding="utf-8")

    result = _guard("app.txt", "--native-only")

    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    assert "Combined file 'cfg[/x]/.env.production' is NOT in .gitignore!" in out


def test_verbose_scanner_details_show_the_version_as_reported() -> None:
    """A version string is whatever the tool printed and may hold brackets."""
    engine = SimpleNamespace(
        get_scanner_info=lambda: [{"name": "gitleaks", "installed": True, "version": "8 [/x]"}]
    )
    console = Console(record=True, force_terminal=False, no_color=True, width=200)

    _print_scan_header(console, cast(ScanEngine, engine), ["gitleaks"], True, True)

    assert "  - gitleaks: installed (v8 [/x])" in console.export_text()
