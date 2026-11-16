"""Messages that embed user text print it exactly as it is.

Most printers interpolated paths, names and error text into Rich markup, some
after ``rich.markup.escape``. escape() does not round-trip: it doubles a
single trailing backslash (``trailing\\`` prints as ``trailing\\\\``) and drops
the backslash in front of a bracket that is not a tag (``C:\\[2024]\\x`` prints
as ``C:[2024]\\x``). The printers that did not escape raised ``MarkupError``
on a closing tag such as ``[/x]``. These tests drive the real CLI where a
command prints the line, and the printer itself otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands import sync_helpers, sync_run_helpers
from envdrift.output import rich as rich_output
from envdrift.scanner.base import EXIT_OPERATIONAL_ERROR
from envdrift.sync.config import SyncConfig
from envdrift.sync.result import ServiceSyncResult, SyncAction

runner = CliRunner()

# Texts rich.markup.escape() cannot round-trip, and one it never had to see.
_TRICKY = ["C:\\[2024]\\x", "trailing\\", "a\\\\[b]", "kv/app[legacy]/key", "cfg[/x]/a.env"]


def _invoke(*args: str):
    return runner.invoke(app, list(args), env={"COLUMNS": "250"})


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("text", _TRICKY)
@pytest.mark.parametrize(
    ("printer", "badge", "console_name"),
    [
        (rich_output.print_success, "[OK]", "console"),
        (rich_output.print_error, "[ERROR]", "diagnostic_console"),
        (rich_output.print_warning, "[WARN]", "diagnostic_console"),
    ],
    ids=["success", "error", "warning"],
)
def test_badge_printers_print_the_message_as_it_is(printer, badge, console_name, text):
    console = getattr(rich_output, console_name)

    with console.capture() as capture:
        printer(f"saw {text}")

    assert capture.get() == f"{badge} saw {text}\n"


def test_error_names_a_backslash_path_as_written(tmp_path: Path) -> None:
    missing = tmp_path / "cfg\\[2024]\\x.env"

    result = _invoke("validate", str(missing), "--schema", "app:Settings")

    assert result.exit_code == 1, result.output
    assert f"[ERROR] ENV file not found: {missing}\n" in result.output


def test_error_keeps_a_single_trailing_backslash(tmp_path: Path) -> None:
    missing = tmp_path / "trailing\\"

    result = _invoke("validate", str(missing), "--schema", "app:Settings")

    assert result.exit_code == 1, result.output
    assert f"[ERROR] ENV file not found: {missing}\n" in result.output


def test_success_message_with_a_closing_tag_does_not_crash(tmp_path: Path) -> None:
    """print_success did not escape at all: ``Generated out[/x].py`` raised MarkupError."""
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")
    (tmp_path / "out[").mkdir()
    output = tmp_path / "out[" / "x].py"

    result = _invoke("init", str(env_file), "--output", str(output))

    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert f"[OK] Generated {output}\n" in result.output


def test_guard_error_names_a_backslash_path_as_written(tmp_path: Path) -> None:
    missing = tmp_path / "cfg\\[2024]\\x"

    result = _invoke("guard", str(missing), "--native-only")

    assert result.exit_code == EXIT_OPERATIONAL_ERROR, result.output
    assert f"Error: Path not found: {missing}\n" in result.output


@pytest.fixture
def bracketed_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The folder ``cfg[/x]``, relative to the cwd, so a report line stays one line.

    An absolute path under a long temp directory wraps a line that holds two of
    them, and the phrase the test looks for is split.
    """
    monkeypatch.chdir(tmp_path)
    folder = Path("cfg[") / "x]"
    folder.mkdir(parents=True)
    return folder


def test_diff_report_shows_bracketed_paths_and_file_names(bracketed_folder: Path) -> None:
    first = bracketed_folder / ".env[bold]"
    first.write_text("A=1\nB=2\n", encoding="utf-8")
    second = bracketed_folder / ".env.prod"
    second.write_text("A=1\nB=3\n", encoding="utf-8")

    result = _invoke("diff", str(first), str(second))

    assert result.exit_code == 0, result.output
    assert result.exception is None
    out = _flat(result.output)
    assert f"Comparing: {first} vs {second}" in out
    assert "┃ .env[bold] ┃ .env.prod ┃" in out


def test_encrypt_check_report_shows_bracketed_paths_and_names(bracketed_folder: Path) -> None:
    env_file = bracketed_folder / ".env.production"
    env_file.write_text("A[/x]_TOKEN=abc123def456ghi789\n", encoding="utf-8")

    result = _invoke("encrypt", str(env_file), "--check")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert f"Encryption Status: {env_file}" in out
    assert "* A[/x]_TOKEN" in out
    assert "* 'A[/x]_TOKEN' has a name suggesting sensitive data" in out
    assert f"Run: envdrift encrypt {env_file}" in out


def test_sync_row_prints_names_paths_and_errors_as_they_are() -> None:
    result = ServiceSyncResult(
        secret_name="kv/C:\\[2024]\\x",
        folder_path=Path("svc[/x]"),
        action=SyncAction.UPDATED,
        message="updated",
        environment="prod[/x]",
        error="vault said [/x] trailing\\",
        local_value_preview="ab[/x]",
        vault_value_preview="cd[bold]",
        backup_path=Path("backups[/x]") / ".env.keys.bak",
    )

    with rich_output.console.capture() as capture:
        rich_output.print_service_sync_status(result)

    out = capture.get()
    folder = Path("svc[/x]")
    assert f"  ~ {folder} (kv/C:\\[2024]\\x, env: prod[/x]) - updated\n" in out
    assert "    Error: vault said [/x] trailing\\\n" in out
    assert "    Local:  ab[/x]\n" in out
    assert "    Vault:  cd[bold]\n" in out
    assert f"    Backup: {Path('backups[/x]') / '.env.keys.bak'}\n" in out


def test_mismatch_warning_prints_the_names_as_they_are() -> None:
    with rich_output.diagnostic_console.capture() as capture:
        rich_output.print_mismatch_warning("svc[/x]", "ab[/x]", "C:\\[2024]\\x")

    assert (
        capture.get() == "\nVALUE MISMATCH: svc[/x]\n  Local:  ab[/x]\n  Vault:  C:\\[2024]\\x\n\n"
    )


_PROGRESS = "Processing: svc\\[2024] (kv/app[/x], env: prod)"


def test_sync_progress_line_prints_the_message_as_it_is() -> None:
    request = sync_run_helpers.SyncRequest(
        config_file=None,
        provider="aws",
        vault_url=None,
        region=None,
        project_id=None,
        verify=False,
        force=False,
        profile=None,
        check_decryption=False,
        validate_schema=False,
        schema=None,
        service_dir=None,
        ci=False,
    )
    context = sync_run_helpers._SyncContext(
        config=SyncConfig(mappings=[]), vault_client=object(), provider="aws"
    )
    engine = sync_run_helpers._new_sync_engine(request, context)
    assert engine.progress_callback is not None

    with rich_output.console.capture() as capture:
        engine.progress_callback(_PROGRESS)

    assert capture.get() == f"{_PROGRESS}\n"


def test_pull_and_lock_progress_line_prints_the_message_as_it_is() -> None:
    config = SyncConfig(mappings=[])
    context = sync_helpers.SyncCommandContext(
        sync_config=config,
        vault_client=object(),
        effective_provider="aws",
        mappings=[],
        filtered_config=config,
    )
    engine = sync_helpers._new_sync_engine(context, force=False)
    assert engine.progress_callback is not None

    with rich_output.console.capture() as capture:
        engine.progress_callback(_PROGRESS)

    assert capture.get() == f"{_PROGRESS}\n"
