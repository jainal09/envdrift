"""Every Rich console envdrift creates prints ``:emoji:`` codes as they are written.

Rich replaces codes such as ``:fire:`` with an emoji by default. Paths, names
and values often hold colons (``:fire:.env`` is a valid file name on Linux and
macOS), so a default console showed a different name than the real one. The
consoles are checked directly, because a report that already prints user text
as ``Text`` would pass even with an emoji-enabled console.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands import agent, guard, install
from envdrift.output import rich as rich_output
from envdrift.scanner import output as scanner_output
from envdrift.scanner.base import EXIT_OPERATIONAL_ERROR, AggregatedScanResult

runner = CliRunner()

_COLON_NAMES = pytest.mark.skipif(
    os.name == "nt", reason="':' is not allowed in a Windows file name"
)


def _prints_codes_literally(console: Console) -> bool:
    return console.render_str("a :fire: b").plain == "a :fire: b"


@pytest.mark.parametrize(
    "console",
    [
        pytest.param(rich_output.console, id="output.rich.console"),
        pytest.param(rich_output.diagnostic_console, id="output.rich.diagnostic_console"),
        pytest.param(guard.console, id="guard.console"),
        pytest.param(guard.diagnostic_console, id="guard.diagnostic_console"),
        pytest.param(install.console, id="install.console"),
        pytest.param(agent.console, id="agent.console"),
    ],
)
def test_module_consoles_leave_emoji_codes_alone(console: Console) -> None:
    assert _prints_codes_literally(console)


@pytest.mark.parametrize(
    ("ci", "json_output", "sarif"),
    [(True, False, False), (False, True, False), (False, False, True)],
    ids=["ci", "json", "sarif"],
)
def test_guard_ci_and_machine_consoles_leave_emoji_codes_alone(
    ci: bool, json_output: bool, sarif: bool
) -> None:
    assert _prints_codes_literally(guard._make_output_console(ci, json_output, sarif))


def test_format_rich_fallback_console_leaves_emoji_codes_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The console format_rich creates when none is passed is checked itself."""
    created: list[Console] = []

    class RecordingConsole(Console):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(scanner_output, "Console", RecordingConsole)
    empty = AggregatedScanResult(
        results=[], total_findings=0, unique_findings=[], scanners_used=[], total_duration_ms=0
    )

    scanner_output.format_rich(empty)

    assert len(created) == 1
    assert _prints_codes_literally(created[0])


def test_error_names_an_emoji_code_path_as_written(tmp_path: Path) -> None:
    missing = tmp_path / ":fire:.env"

    result = runner.invoke(app, ["validate", str(missing), "--schema", "app:Settings"])

    assert result.exit_code == 1, result.output
    out = "".join(result.output.split())
    assert "".join(f"ENV file not found: {missing}".split()) in out


def test_guard_error_names_an_emoji_code_path_as_written(tmp_path: Path) -> None:
    missing = tmp_path / ":fire:"

    result = runner.invoke(app, ["guard", str(missing), "--native-only"])

    assert result.exit_code == EXIT_OPERATIONAL_ERROR, result.output
    out = "".join(result.output.split())
    assert "".join(f"Path not found: {missing}".split()) in out


@_COLON_NAMES
def test_guard_ci_report_names_an_emoji_code_file_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wide --ci table showed the finding's description with an emoji."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ":fire:.env").write_text(
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLQ\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["guard", ".", "--native-only", "--ci"], env={"COLUMNS": "250"})

    assert result.exit_code not in (0, EXIT_OPERATIONAL_ERROR), result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Environment file ':fire:.env' is not encrypted" in result.output
    assert "\N{FIRE}" not in result.output
